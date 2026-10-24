// Copyright (c) 2026 - Nicholas Fedor <nick@nickfedor.com>
// SPDX-License-Identifier: AGPL-3.0-or-later

package output

import (
	"errors"
	"fmt"
	"io"

	"github.com/nicholas-fedor/agh-cli/internal/app"
)

// WriteMutationResults writes one line per instance a mutation changed.
//
// Parameters:
//   - writer: destination for the result lines.
//   - results: per-instance mutation results in execution order.
//
// Returns:
//   - error: joined errors from every failed line write.
func WriteMutationResults(writer io.Writer, results []app.MutationResult) error {
	errs := make([]error, 0, len(results))

	for _, result := range results {
		_, err := fmt.Fprintf(writer, "[%s] %s\n", result.Instance, result.Message)
		if err != nil {
			errs = append(errs, fmt.Errorf("write instance %q result: %w", result.Instance, err))
		}
	}

	return errors.Join(errs...)
}

// writeInstanceHeader writes the separator and heading of one instance table.
//
// A run that selected one instance writes neither, because the table needs no
// heading. Every table after the first is separated from the one before it by a
// blank line.
//
// Parameters:
//   - writer: destination for the separator and heading.
//   - position: zero-based position of the table among the written tables.
//   - instanceCount: number of selected instances.
//   - instance: name of the instance the table belongs to.
//
// Returns:
//   - error: a wrapped error when the separator or heading cannot be written.
func writeInstanceHeader(writer io.Writer, position, instanceCount int, instance string) error {
	if instanceCount <= 1 {
		return nil
	}

	if position > 0 {
		_, err := fmt.Fprintln(writer)
		if err != nil {
			return fmt.Errorf("write instance separator: %w", err)
		}
	}

	_, err := fmt.Fprintf(writer, "Instance: %s\n", instance)
	if err != nil {
		return fmt.Errorf("write instance %q header: %w", instance, err)
	}

	return nil
}
