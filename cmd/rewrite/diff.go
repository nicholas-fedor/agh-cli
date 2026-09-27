// Copyright (c) 2026 - Nicholas Fedor <nick@nickfedor.com>
// SPDX-License-Identifier: AGPL-3.0-or-later

package rewrite

import (
	"fmt"
	"strings"

	"github.com/spf13/cobra"

	"github.com/nicholas-fedor/agh-cli/internal/app"
	"github.com/nicholas-fedor/agh-cli/internal/output"
)

// newRewriteDiffCommand creates the diff command and binds its flags.
//
// Returns:
//   - *cobra.Command: The diff command with its own flag values.
func newRewriteDiffCommand() *cobra.Command {
	values := &flagValues{}

	command := &cobra.Command{
		Use:   "diff [<instance> <instance>]",
		Short: "Compare rewrite rules between instances or against a file",
		Long: `Diff rewrite rules between two configured instances, or between an instance and a local file.
Specify two instances with --instance flags, or one instance with --file.`,
		RunE: func(cmd *cobra.Command, args []string) error {
			return runRewriteDiff(cmd, args, values)
		},
	}

	command.Flags().StringVarP(&values.file, "file", "f", "", "path to YAML/JSON rewrite rules file")
	command.Flags().BoolVarP(&values.all, "all", "a", false, "target all instances")
	command.Flags().StringSliceVarP(&values.names, "instance", "i", []string{}, "target instance name(s)")
	command.Flags().StringVarP(&values.sortColumn, "sort", "s", "domain", "sort column (domain, answer, status)")

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
//   - error: An error when a selection, per-instance request, or the diff output
//     fails.
func runRewriteDiff(cmd *cobra.Command, _ []string, values *flagValues) error {
	selection, err := values.selection()
	if err != nil {
		return fmt.Errorf("select rewrite instances: %w", err)
	}

	result, diffErr := app.NewRewriteManagement().Diff(
		cmd.Context(),
		selection,
		values.file,
	)
	if diffErr != nil {
		return fmt.Errorf("run rewrite diff: %w", diffErr)
	}

	outputErr := writeRewriteDiff(cmd, result, values.sortColumn)
	if outputErr != nil {
		return fmt.Errorf("write rewrite diff: %w", outputErr)
	}

	return nil
}

// writeRewriteDiff renders one completed rewrite diff.
//
// Parameters:
//   - cmd: Cobra command receiving the rendered diff table.
//   - result: One completed rewrite diff.
//   - sortColumn: Selected sort column, or an empty value for the default.
//
// Returns:
//   - error: An error when the diff table cannot be written.
func writeRewriteDiff(
	cmd *cobra.Command,
	result app.RewriteDiffResult,
	sortColumn string,
) error {
	headers := []string{"DOMAIN", "LOCAL", "REMOTE", "CHANGE"}
	if result.Mode == app.RewriteDiffInstances {
		headers[1] = strings.ToUpper(result.InstanceNames[0])
		headers[2] = strings.ToUpper(result.InstanceNames[1])
	}

	tableWriter := output.NewTableWriter(headers...)
	for _, entry := range result.Diff.Added {
		tableWriter.Row(entry.Domain, "-", formatRewriteRule(entry.New), entry.Change)
	}

	for _, entry := range result.Diff.Removed {
		tableWriter.Row(entry.Domain, formatRewriteRule(entry.Old), "-", entry.Change)
	}

	for _, entry := range result.Diff.Modified {
		tableWriter.Row(
			entry.Domain,
			formatRewriteRule(entry.Old),
			formatRewriteRule(entry.New),
			entry.Change,
		)
	}

	applyRewriteSort(tableWriter, sortColumn, "DOMAIN")

	writer := cmd.OutOrStdout()
	_, err := tableWriter.WriteTo(writer)
	if err != nil {
		return fmt.Errorf("write rewrite diff: %w", err)
	}

	return nil
}

// formatRewriteRule formats one optional display rule.
//
// Parameters:
//   - rule: Optional rewrite rule, rendered as a placeholder when absent.
//
// Returns:
//   - string: The formatted answer, or a placeholder for an absent rule.
func formatRewriteRule(rule *app.RewriteRule) string {
	if rule == nil {
		return "-"
	}

	return output.FormatRewrite(output.RewriteValue{
		Answer:  rule.Answer,
		Enabled: rule.Enabled,
	})
}
