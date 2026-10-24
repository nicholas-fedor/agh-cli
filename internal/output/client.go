// Copyright (c) 2026 - Nicholas Fedor <nick@nickfedor.com>
// SPDX-License-Identifier: AGPL-3.0-or-later

package output

import (
	"errors"
	"fmt"
	"io"

	"github.com/nicholas-fedor/agh-cli/internal/app"
)

// WriteClientList writes one client table per instance that answered.
//
// Parameters:
//   - writer: destination for the tables.
//   - results: per-instance list results in configuration order.
//
// Returns:
//   - error: joined errors from every table that could not be written.
func WriteClientList(writer io.Writer, results []app.ClientListResult) error {
	errs := make([]error, 0, len(results))

	for position, result := range results {
		err := writeClientTable(writer, position, result)
		if err != nil {
			errs = append(errs, err)
		}
	}

	return errors.Join(errs...)
}

// writeClientTable writes the client table of one instance.
//
// Parameters:
//   - writer: destination for the table.
//   - position: zero-based position of the table among the written tables.
//   - result: list result of one instance.
//
// Returns:
//   - error: a wrapped error when the heading or the table cannot be written.
func writeClientTable(writer io.Writer, position int, result app.ClientListResult) error {
	err := writeInstanceHeader(writer, position, result.InstanceCount, result.Instance)
	if err != nil {
		return fmt.Errorf("write instance %q client list header: %w", result.Instance, err)
	}

	tableWriter := NewTableWriter("INSTANCE", "NAME", "TYPE")
	for _, row := range result.Rows {
		tableWriter.Row(result.Instance, row.Name, FormatClientType(row.Automatic))
	}

	_, err = tableWriter.WriteTo(writer)
	if err != nil {
		return fmt.Errorf("write instance %q: %w", result.Instance, err)
	}

	return nil
}
