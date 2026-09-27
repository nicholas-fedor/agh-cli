// Copyright (c) 2026 - Nicholas Fedor <nick@nickfedor.com>
// SPDX-License-Identifier: AGPL-3.0-or-later

package rewrite

import (
	"context"

	"github.com/spf13/cobra"

	"github.com/nicholas-fedor/agh-cli/internal/app"
)

// newRewriteUpdateCommand creates the update command and binds its flags.
//
// Returns:
//   - *cobra.Command: The update command with its own flag values.
func newRewriteUpdateCommand() *cobra.Command {
	command, values := newRewriteRuleCommand(
		"update <domain> <answer>",
		"Update a rewrite rule",
		"update rewrite",
		func(
			management *app.RewriteManagement,
			ctx context.Context,
			selection app.RewriteSelection,
			request app.RewriteRuleInput,
		) ([]app.RewriteMutationResult, error) {
			return management.Update(ctx, selection, request)
		},
	)

	command.Flags().BoolVarP(&values.enabled, "enabled", "e", true, "enable rule")
	command.Flags().BoolVarP(&values.all, "all", "a", false, "target all instances")
	command.Flags().StringSliceVarP(&values.names, "instance", "i", []string{}, "target instance name(s)")

	return command
}
