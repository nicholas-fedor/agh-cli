// Copyright (c) 2026 - Nicholas Fedor <nick@nickfedor.com>
// SPDX-License-Identifier: AGPL-3.0-or-later

package username

import (
	"fmt"

	"github.com/spf13/cobra"
)

// newClearCommand creates the username clear command.
//
// The command removes only the username. A stored credential reference and a
// plaintext password both survive, so an instance keeps its password after the
// identity it pairs with is removed.
//
// Parameters:
//   - seams: credential coordinator factory.
//
// Returns:
//   - *cobra.Command: The clear command.
func newClearCommand(seams *streams) *cobra.Command {
	return &cobra.Command{
		Use:   "clear <instance>",
		Short: "Remove the administrator username of a configured instance",
		Long: `Remove the AdGuard Home administrator username of a configured
instance. Only the username is removed, so a stored password keeps
working. Use 'agh-cli instance credentials password set <instance>' to
change the password without restoring a username.`,
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			return runClear(cmd, args, seams)
		},
	}
}

// runClear removes the administrator username of one configured instance.
//
// Parameters:
//   - cmd: Cobra command context.
//   - args: positional arguments, where args[0] is the instance name.
//   - seams: credential coordinator factory.
//
// Returns:
//   - error: a wrapped error when the coordinator cannot be built, the instance
//     is unknown, or the configuration cannot be written.
func runClear(cmd *cobra.Command, args []string, seams *streams) error {
	name := args[0]

	store, err := seams.coordinator()
	if err != nil {
		return fmt.Errorf("build credential coordinator: %w", err)
	}

	_, err = store.ClearUsername(name)
	if err != nil {
		return fmt.Errorf("clear username for %q: %w", name, err)
	}

	cmd.Printf("Username for instance %q cleared.\n", name)

	return nil
}
