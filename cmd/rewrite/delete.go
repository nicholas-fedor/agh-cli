// Copyright (c) 2026 - Nicholas Fedor <nick@nickfedor.com>
// SPDX-License-Identifier: AGPL-3.0-or-later

package rewrite

import (
	"context"
	"errors"
	"fmt"

	"github.com/spf13/cobra"

	"github.com/nicholas-fedor/agh-cli/internal/app"
)

// errAnswerRequired indicates that rewrite deletion lacks its answer flag.
var errAnswerRequired = errors.New("--answer is required when deleting a rewrite rule")

// newRewriteDeleteCommand creates the delete command and binds its flags.
//
// Returns:
//   - *cobra.Command: The delete command with its own flag values.
func newRewriteDeleteCommand() *cobra.Command {
	values := &flagValues{}

	command := &cobra.Command{
		Use:   "delete <domain>",
		Short: "Delete a rewrite rule",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			return runRewriteDelete(cmd, args, values)
		},
	}

	command.Flags().StringVarP(&values.answer, "answer", "A", "", "answer/IP to delete")
	command.Flags().BoolVarP(&values.enabled, "enabled", "e", true, "rule enabled state")
	command.Flags().BoolVarP(&values.all, "all", "a", false, "target all instances")
	command.Flags().StringSliceVarP(&values.names, "instance", "i", []string{}, "target instance name(s)")

	return command
}

// runRewriteDelete removes a DNS rewrite rule from one or more instances.
//
// Parameters:
//   - cmd: Cobra command context and rewrite flag access.
//   - args: Domain argument.
//   - values: Bound flag values selecting the answer and target instances.
//
// Returns:
//   - error: An error when the answer flag is missing or a per-instance
//     request fails.
func runRewriteDelete(cmd *cobra.Command, args []string, values *flagValues) error {
	if values.answer == "" {
		return errAnswerRequired
	}

	err := runRewriteRuleMutation(
		cmd,
		values,
		args[0],
		values.answer,
		func(
			management *app.RewriteManagement,
			ctx context.Context,
			selection app.RewriteSelection,
			request app.RewriteRuleInput,
		) ([]app.RewriteMutationResult, error) {
			return management.Delete(ctx, selection, request)
		},
	)
	if err != nil {
		return fmt.Errorf("delete rewrite rule: %w", err)
	}

	return nil
}
