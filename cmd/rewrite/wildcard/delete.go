// Copyright (c) 2026 - Nicholas Fedor <nick@nickfedor.com>
// SPDX-License-Identifier: AGPL-3.0-or-later

package wildcard

import (
	"errors"
	"fmt"

	"github.com/spf13/cobra"

	"github.com/nicholas-fedor/agh-cli/internal/app"
	"github.com/nicholas-fedor/agh-cli/internal/flags"
	"github.com/nicholas-fedor/agh-cli/internal/output"
)

// newWildcardRemoveCommand creates the remove command and binds its flags.
//
// Returns:
//   - *cobra.Command: The remove command with its own flag values.
func newWildcardRemoveCommand() *cobra.Command {
	return newWildcardZoneCommand("remove <domain>", "Remove wildcard rewrite rules for a zone", runWildcardDelete)
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
func runWildcardDelete(cmd *cobra.Command, args []string, values *flags.InstanceSelection) error {
	results, deleteErr := app.NewRewriteManagement(cmd.Context()).WildcardDelete(
		cmd.Context(),
		values.Selection(),
		args[0],
	)
	outputErr := output.WriteMutationResults(cmd.OutOrStdout(), results)

	deleteErr = errors.Join(deleteErr, outputErr)
	if deleteErr != nil {
		return fmt.Errorf("remove wildcard rewrite rules: %w", deleteErr)
	}

	return nil
}
