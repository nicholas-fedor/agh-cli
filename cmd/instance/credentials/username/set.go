// Copyright (c) 2026 - Nicholas Fedor <nick@nickfedor.com>
// SPDX-License-Identifier: AGPL-3.0-or-later

package username

import (
	"fmt"

	"github.com/spf13/cobra"

	"github.com/nicholas-fedor/agh-cli/internal/app"
	"github.com/nicholas-fedor/agh-cli/internal/output"
)

// newSetCommand creates the username set command.
//
// The command accepts the username as an argument because a username is not a
// secret. Unlike a password, it is safe in a process listing and in shell
// history, and an argument keeps the command scriptable.
//
// Returns:
//   - *cobra.Command: The set command.
func newSetCommand() *cobra.Command {
	return &cobra.Command{
		Use:   "set <instance> <username>",
		Short: "Set the administrator username of a configured instance",
		Long: `Set the AdGuard Home administrator username of a configured instance.
The change is written to the configuration file and never reaches the
credential store, so a stored password keeps working. Use 'agh-cli
instance credentials password set <instance>' to change the password
without disturbing the username.`,
		Args: cobra.ExactArgs(2),
		RunE: runSet,
	}
}

// runSet records the administrator username of one configured instance.
//
// Parameters:
//   - cmd: Cobra command context.
//   - args: positional arguments, where args[0] is the instance name and args[1]
//     is the username.
//
// Returns:
//   - error: a wrapped error when no configuration is loaded, the instance is
//     unknown, or the configuration cannot be written.
func runSet(cmd *cobra.Command, args []string) error {
	name, username := args[0], args[1]

	_, err := app.SetUsername(cmd.Context(), name, username)
	if err != nil {
		return fmt.Errorf("set username for %q: %w", name, err)
	}

	err = output.WriteUsernameSet(cmd.OutOrStdout(), name, username)
	if err != nil {
		return fmt.Errorf("report username for %q: %w", name, err)
	}

	return nil
}
