// Copyright (c) 2026 - Nicholas Fedor <nick@nickfedor.com>
// SPDX-License-Identifier: AGPL-3.0-or-later

package wildcard

import (
	"errors"
	"fmt"

	"github.com/spf13/cobra"

	"github.com/nicholas-fedor/agh-cli/internal/app"
)

// newWildcardRemoveCommand creates the remove command and binds its flags.
//
// Returns:
//   - *cobra.Command: The remove command with its own flag values.
func newWildcardRemoveCommand() *cobra.Command {
	command, values := newWildcardZoneCommand(
		"remove <domain>",
		"Remove wildcard rewrite rules for a zone",
		runWildcardDelete,
	)

	command.Flags().BoolVarP(&values.all, "all", "a", false, "target all instances")
	command.Flags().StringSliceVarP(&values.names, "instance", "i", []string{}, "target instance name(s)")

	return command
}

// runWildcardDelete removes wildcard rules from selected instances.
//
// Parameters:
//   - cmd: Cobra command context.
//   - args: Zone domain argument.
//   - values: Bound flag values selecting the target instances.
//
// Returns:
//   - error: An error when a selection, per-instance request, or the mutation
//     output fails.
func runWildcardDelete(cmd *cobra.Command, args []string, values *flagValues) error {
	selection, err := values.selection()
	if err != nil {
		return fmt.Errorf("select rewrite instances: %w", err)
	}

	results, deleteErr := app.NewRewriteManagement().WildcardDelete(
		cmd.Context(),
		selection,
		args[0],
	)
	outputErr := writeWildcardMutationResults(cmd, results)

	deleteErr = errors.Join(deleteErr, outputErr)
	if deleteErr != nil {
		return fmt.Errorf("remove wildcard rewrite rules: %w", deleteErr)
	}

	return nil
}
