// Copyright (c) 2026 - Nicholas Fedor <nick@nickfedor.com>
// SPDX-License-Identifier: AGPL-3.0-or-later

package rewrite

import (
	"errors"
	"fmt"

	"github.com/spf13/cobra"

	"github.com/nicholas-fedor/agh-cli/internal/app"
	"github.com/nicholas-fedor/agh-cli/internal/flags"
	"github.com/nicholas-fedor/agh-cli/internal/output"
)

// newRewriteUpdateCommand creates the update command and binds its flags.
//
// Returns:
//   - *cobra.Command: The update command with its own flag values.
func newRewriteUpdateCommand() *cobra.Command {
	return newRewriteRuleCommand("update <domain> <answer>", "Update a rewrite rule", runRewriteUpdate)
}

// runRewriteUpdate replaces a rewrite rule on one or more instances.
//
// Parameters:
//   - cmd: Cobra command providing output and context.
//   - args: Domain and answer arguments.
//   - values: Bound flag values selecting the instances and rule state.
//
// Returns:
//   - error: An error when a per-instance request or the result output fails.
func runRewriteUpdate(cmd *cobra.Command, args []string, values *flags.RewriteRuleFlags) error {
	results, mutationErr := app.NewRewriteManagement(cmd.Context()).Update(
		cmd.Context(),
		values.Selection(),
		values.Request(args[0], args[1]),
	)
	outputErr := output.WriteMutationResults(cmd.OutOrStdout(), results)

	err := errors.Join(mutationErr, outputErr)
	if err != nil {
		return fmt.Errorf("update rewrite: %w", err)
	}

	return nil
}
