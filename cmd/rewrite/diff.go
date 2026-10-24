// Copyright (c) 2026 - Nicholas Fedor <nick@nickfedor.com>
// SPDX-License-Identifier: AGPL-3.0-or-later

package rewrite

import (
	"fmt"

	"github.com/spf13/cobra"

	"github.com/nicholas-fedor/agh-cli/internal/app"
	"github.com/nicholas-fedor/agh-cli/internal/flags"
	"github.com/nicholas-fedor/agh-cli/internal/output"
)

// newRewriteDiffCommand creates the diff command and binds its flags.
//
// Returns:
//   - *cobra.Command: The diff command with its own flag values.
func newRewriteDiffCommand() *cobra.Command {
	values := new(flags.RewriteDiffFlags)

	command := &cobra.Command{
		Use:   "diff [<instance> <instance>]",
		Short: "Compare rewrite rules between instances or against a file",
		Long: `Diff rewrite rules between two configured instances, or between an instance and a local file.
Specify two instances with --instance flags, or one instance with --file.`,
		RunE: func(cmd *cobra.Command, args []string) error {
			return runRewriteDiff(cmd, args, values)
		},
	}

	values.Bind(command.Flags())

	return command
}

// runRewriteDiff compares rewrite rules between instances or against a file.
//
// Parameters:
//   - cmd: Cobra command context.
//   - args: Unused positional arguments.
//   - values: Bound flag values selecting the comparison source and instances.
//
// Returns:
//   - error: An error when the sort column is unknown, or when a selection,
//     per-instance request, or the diff output fails.
func runRewriteDiff(cmd *cobra.Command, _ []string, values *flags.RewriteDiffFlags) error {
	err := values.Validate()
	if err != nil {
		return fmt.Errorf("run rewrite diff: %w", err)
	}

	result, diffErr := app.NewRewriteManagement(cmd.Context()).Diff(
		cmd.Context(),
		values.Selection(),
		values.File,
	)
	if diffErr != nil {
		return fmt.Errorf("run rewrite diff: %w", diffErr)
	}

	outputErr := output.WriteRewriteDiff(cmd.OutOrStdout(), result, values.Sort)
	if outputErr != nil {
		return fmt.Errorf("write rewrite diff: %w", outputErr)
	}

	return nil
}
