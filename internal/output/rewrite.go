// Copyright (c) 2026 - Nicholas Fedor <nick@nickfedor.com>
// SPDX-License-Identifier: AGPL-3.0-or-later

package output

import (
	"errors"
	"fmt"
	"io"
	"strings"

	"github.com/nicholas-fedor/agh-cli/internal/app"
)

// WriteRewriteLists writes one rule table per instance that answered.
//
// Parameters:
//   - writer: destination for the tables.
//   - results: per-instance list results in configuration order.
//   - sortColumn: requested sort column, or an empty string for the default.
//
// Returns:
//   - error: joined errors from every table that could not be written.
func WriteRewriteLists(writer io.Writer, results []app.RewriteListResult, sortColumn string) error {
	errs := make([]error, 0, len(results))

	for position, result := range results {
		err := writeRewriteList(writer, position, result, sortColumn)
		if err != nil {
			errs = append(errs, err)
		}
	}

	return errors.Join(errs...)
}

// WriteRewriteDiff writes the table of one completed rewrite diff.
//
// The side columns are named after the compared instances when two instances
// are compared, and are named LOCAL and REMOTE when a file is compared with an
// instance.
//
// Parameters:
//   - writer: destination for the table.
//   - result: completed rewrite diff.
//   - sortColumn: requested sort column, or an empty string for the default.
//
// Returns:
//   - error: a wrapped error when the table cannot be written.
func WriteRewriteDiff(writer io.Writer, result app.RewriteDiffResult, sortColumn string) error {
	headers := []string{"DOMAIN", "LOCAL", "REMOTE", "CHANGE"}
	if result.Mode == app.RewriteDiffInstances {
		headers[1] = strings.ToUpper(result.InstanceNames[0])
		headers[2] = strings.ToUpper(result.InstanceNames[1])
	}

	tableWriter := NewTableWriter(headers...)
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

	tableWriter.SortRewrite(sortColumn, "DOMAIN")

	_, err := tableWriter.WriteTo(writer)
	if err != nil {
		return fmt.Errorf("write rewrite diff: %w", err)
	}

	return nil
}

// WriteRewriteSettings writes one settings line per instance that answered.
//
// Parameters:
//   - writer: destination for the settings lines.
//   - results: per-instance settings results in configuration order.
//
// Returns:
//   - error: joined errors from every failed line write.
func WriteRewriteSettings(writer io.Writer, results []app.RewriteSettingsResult) error {
	errs := make([]error, 0, len(results))

	for _, result := range results {
		_, err := fmt.Fprintf(writer, "[%s] {\"enabled\":%t}\n", result.Instance, result.Enabled)
		if err != nil {
			errs = append(errs, fmt.Errorf("write instance %q settings: %w", result.Instance, err))
		}
	}

	return errors.Join(errs...)
}

// writeRewriteList writes the rule table of one instance.
//
// Parameters:
//   - writer: destination for the table.
//   - position: zero-based position of the table among the written tables.
//   - result: list result of one instance.
//   - sortColumn: requested sort column, or an empty string for the default.
//
// Returns:
//   - error: a wrapped error when the heading or the table cannot be written.
func writeRewriteList(writer io.Writer, position int, result app.RewriteListResult, sortColumn string) error {
	err := writeInstanceHeader(writer, position, result.InstanceCount, result.Instance)
	if err != nil {
		return fmt.Errorf("write instance %q rewrite list header: %w", result.Instance, err)
	}

	tableWriter := NewTableWriter("INSTANCE", "DOMAIN", "ANSWER", "STATUS")
	for _, rule := range result.Rules {
		tableWriter.Row(result.Instance, rule.Domain, rule.Answer, FormatRewriteStatus(rule.Enabled))
	}

	tableWriter.SortRewrite(sortColumn, "INSTANCE")

	_, err = tableWriter.WriteTo(writer)
	if err != nil {
		return fmt.Errorf("write instance %q rewrite rules: %w", result.Instance, err)
	}

	return nil
}

// formatRewriteRule formats one optional diff side.
//
// Parameters:
//   - rule: optional rewrite rule, written as a placeholder when absent.
//
// Returns:
//   - string: the formatted answer and state, or "-" for an absent rule.
func formatRewriteRule(rule *app.RewriteRule) string {
	if rule == nil {
		return "-"
	}

	return FormatRewrite(RewriteValue{Answer: rule.Answer, Enabled: rule.Enabled})
}
