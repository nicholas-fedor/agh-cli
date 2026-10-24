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

// newRewriteDeleteCommand creates the delete command and binds its flags.
//
// Returns:
//   - *cobra.Command: The delete command with its own flag values.
func newRewriteDeleteCommand() *cobra.Command {
	values := new(flags.RewriteDeleteFlags)

	command := &cobra.Command{
		Use:   "delete <domain>",
		Short: "Delete a rewrite rule",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			return runRewriteDelete(cmd, args, values)
		},
	}

	values.Bind(command.Flags())

	return command
}

// runRewriteDelete removes a DNS rewrite rule from one or more instances.
//
// Parameters:
//   - cmd: Cobra command providing output and context.
//   - args: Domain argument.
//   - values: Bound flag values selecting the answer and target instances.
//
// Returns:
//   - error: An error when the answer flag is missing or a per-instance
//     request fails.
func runRewriteDelete(cmd *cobra.Command, args []string, values *flags.RewriteDeleteFlags) error {
	err := values.Validate()
	if err != nil {
		return fmt.Errorf("delete rewrite rule: %w", err)
	}

	results, mutationErr := app.NewRewriteManagement(cmd.Context()).Delete(
		cmd.Context(),
		values.Selection(),
		values.Request(args[0]),
	)
	outputErr := output.WriteMutationResults(cmd.OutOrStdout(), results)

	err = errors.Join(mutationErr, outputErr)
	if err != nil {
		return fmt.Errorf("delete rewrite rule: %w", err)
	}

	return nil
}
