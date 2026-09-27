// Copyright (c) 2026 - Nicholas Fedor <nick@nickfedor.com>
// SPDX-License-Identifier: AGPL-3.0-or-later

package rewrite

import (
	"context"

	"github.com/spf13/cobra"

	"github.com/nicholas-fedor/agh-cli/internal/app"
)

// newRewriteAddCommand creates the add command and binds its flags.
//
// Returns:
//   - *cobra.Command: The add command with its own flag values.
func newRewriteAddCommand() *cobra.Command {
	command, values := newRewriteRuleCommand(
		"add <domain> <answer>",
		"Add a rewrite rule",
		"add rewrite",
		func(
			management *app.RewriteManagement,
			ctx context.Context,
			selection app.RewriteSelection,
			request app.RewriteRuleInput,
		) ([]app.RewriteMutationResult, error) {
			return management.Add(ctx, selection, request)
		},
	)

	command.Flags().BoolVarP(&values.enabled, "enabled", "e", true, "enable rule")
	command.Flags().BoolVarP(&values.all, "all", "a", false, "target all instances")
	command.Flags().StringSliceVarP(&values.names, "instance", "i", []string{}, "target instance name(s)")

	return command
}
