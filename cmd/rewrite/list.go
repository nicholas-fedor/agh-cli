// Copyright (c) 2026 - Nicholas Fedor <nick@nickfedor.com>
// SPDX-License-Identifier: AGPL-3.0-or-later

package rewrite

import (
	"errors"
	"fmt"
	"io"

	"github.com/spf13/cobra"

	"github.com/nicholas-fedor/agh-cli/internal/app"
	"github.com/nicholas-fedor/agh-cli/internal/output"
)

// newRewriteListCommand creates the list command and binds its flags.
//
// Returns:
//   - *cobra.Command: The list command with its own flag values.
func newRewriteListCommand() *cobra.Command {
	values := &flagValues{}

	command := &cobra.Command{
		Use:   "list",
		Short: "List rewrite rules",
		RunE: func(cmd *cobra.Command, args []string) error {
			return runRewriteList(cmd, args, values)
		},
	}

	command.Flags().BoolVarP(&values.all, "all", "a", false, "target all instances")
	command.Flags().StringSliceVarP(&values.names, "instance", "i", []string{}, "target instance name(s)")
	command.Flags().StringVarP(&values.sortColumn, "sort", "s", "domain", "sort column (domain, answer, status)")

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
//   - error: An error when a selection, per-instance request, or the list output
//     fails.
func runRewriteList(cmd *cobra.Command, _ []string, values *flagValues) error {
	selection, err := values.selection()
	if err != nil {
		return fmt.Errorf("select rewrite instances: %w", err)
	}

	results, listErr := app.NewRewriteManagement().List(cmd.Context(), selection)
	outputErr := writeRewriteLists(cmd, results, values.sortColumn)

	listErr = errors.Join(listErr, outputErr)
	if listErr != nil {
		return fmt.Errorf("list rewrite rules: %w", listErr)
	}

	return nil
}

// writeRewriteLists renders every successful rewrite list result.
//
// Parameters:
//   - cmd: Cobra command receiving the rendered tables.
//   - results: Per-instance rewrite list results to render.
//   - sortColumn: Selected sort column, or an empty value for the default.
//
// Returns:
//   - error: Joined errors from every failed instance table.
func writeRewriteLists(
	cmd *cobra.Command,
	results []app.RewriteListResult,
	sortColumn string,
) error {
	errs := make([]error, 0, len(results))

	for _, result := range results {
		err := writeRewriteList(cmd, result, sortColumn)
		if err != nil {
			errs = append(errs, err)
		}
	}

	return errors.Join(errs...)
}

// writeRewriteList renders one rewrite list result.
//
// Parameters:
//   - cmd: Cobra command receiving the rendered table.
//   - result: One per-instance rewrite list result.
//   - sortColumn: Selected sort column, or an empty value for the default.
//
// Returns:
//   - error: An error when the instance table cannot be written.
func writeRewriteList(
	cmd *cobra.Command,
	result app.RewriteListResult,
	sortColumn string,
) error {
	writer := cmd.OutOrStdout()
	err := writeRewriteListHeader(writer, result)
	if err != nil {
		return fmt.Errorf("write instance %q rewrite list header: %w", result.Instance, err)
	}

	tableWriter := output.NewTableWriter("INSTANCE", "DOMAIN", "ANSWER", "STATUS")
	for _, rule := range result.Rules {
		tableWriter.Row(
			result.Instance,
			rule.Domain,
			rule.Answer,
			output.FormatRewriteStatus(rule.Enabled),
		)
	}

	applyRewriteSort(tableWriter, sortColumn, "INSTANCE")

	_, err = tableWriter.WriteTo(writer)
	if err != nil {
		return fmt.Errorf("write instance %q rewrite rules: %w", result.Instance, err)
	}

	return nil
}

// writeRewriteListHeader renders separators and multi-instance headers.
//
// Parameters:
//   - writer: Destination for the separator and instance header.
//   - result: One per-instance rewrite list result.
//
// Returns:
//   - error: An error when the separator or header cannot be written.
func writeRewriteListHeader(writer io.Writer, result app.RewriteListResult) error {
	var err error

	if result.Index > 0 && result.InstanceCount > 1 {
		_, err = fmt.Fprintln(writer)
		if err != nil {
			return fmt.Errorf("write instance separator: %w", err)
		}
	}

	if result.InstanceCount <= 1 {
		return nil
	}

	_, err = fmt.Fprintf(writer, "Instance: %s\n", result.Instance)
	if err != nil {
		return fmt.Errorf("write instance %q header: %w", result.Instance, err)
	}

	return nil
}
