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

// newRewriteListCommand creates the list command and binds its flags.
//
// Returns:
//   - *cobra.Command: The list command with its own flag values.
func newRewriteListCommand() *cobra.Command {
	values := new(flags.RewriteListFlags)

	command := &cobra.Command{
		Use:   "list",
		Short: "List rewrite rules",
		RunE: func(cmd *cobra.Command, args []string) error {
			return runRewriteList(cmd, args, values)
		},
	}

	values.Bind(command.Flags())

	return command
}

// runRewriteList lists rewrite rules across one or more instances.
//
// Parameters:
//   - cmd: Cobra command context.
//   - args: Unused positional arguments.
//   - values: Bound flag values selecting the target instances.
//
// Returns:
//   - error: An error when the sort column is unknown, or when a selection,
//     per-instance request, or the list output fails.
func runRewriteList(cmd *cobra.Command, _ []string, values *flags.RewriteListFlags) error {
	err := values.Validate()
	if err != nil {
		return fmt.Errorf("list rewrite rules: %w", err)
	}

	results, listErr := app.NewRewriteManagement(cmd.Context()).List(cmd.Context(), values.Selection())
	outputErr := output.WriteRewriteLists(cmd.OutOrStdout(), results, values.Sort)

	listErr = errors.Join(listErr, outputErr)
	if listErr != nil {
		return fmt.Errorf("list rewrite rules: %w", listErr)
	}

	return nil
}
