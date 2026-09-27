// Copyright (c) 2026 - Nicholas Fedor <nick@nickfedor.com>
// SPDX-License-Identifier: AGPL-3.0-or-later

package wildcard

import (
	"errors"
	"fmt"

	"github.com/spf13/cobra"

	"github.com/nicholas-fedor/agh-cli/internal/app"
)

// newWildcardAddCommand creates the add command and binds its flags.
//
// Returns:
//   - *cobra.Command: The add command with its own flag values.
func newWildcardAddCommand() *cobra.Command {
	command, values := newWildcardZoneCommand(
		"add <domain>",
		"Add wildcard rewrite rules for a zone",
		runWildcardAdd,
	)

	command.Flags().BoolVarP(&values.all, "all", "a", false, "target all instances")
	command.Flags().StringSliceVarP(&values.names, "instance", "i", []string{}, "target instance name(s)")

	return command
}

// runWildcardAdd creates wildcard rules for selected instances.
//
// Parameters:
//   - cmd: Cobra command context.
//   - args: Zone domain argument.
//   - values: Bound flag values selecting the target instances.
//
// Returns:
//   - error: An error when a selection, per-instance request, or the mutation
//     output fails.
func runWildcardAdd(cmd *cobra.Command, args []string, values *flagValues) error {
	selection, err := values.selection()
	if err != nil {
		return fmt.Errorf("select rewrite instances: %w", err)
	}

	results, addErr := app.NewRewriteManagement().WildcardAdd(
		cmd.Context(),
		selection,
		args[0],
	)
	outputErr := writeWildcardMutationResults(cmd, results)

	addErr = errors.Join(addErr, outputErr)
	if addErr != nil {
		return fmt.Errorf("add wildcard rewrite rules: %w", addErr)
	}

	return nil
}
