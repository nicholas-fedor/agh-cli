// Copyright (c) 2026 - Nicholas Fedor <nick@nickfedor.com>
// SPDX-License-Identifier: AGPL-3.0-or-later

package client

import (
	"errors"
	"fmt"

	"github.com/spf13/cobra"

	"github.com/nicholas-fedor/agh-cli/internal/app"
	"github.com/nicholas-fedor/agh-cli/internal/output"
)

// newClientListCommand creates the list command and binds its flags.
//
// Returns:
//   - *cobra.Command: The list command with its own flag values.
func newClientListCommand() *cobra.Command {
	values := &selectionValues{}

	command := &cobra.Command{
		Use:   "list",
		Short: "List clients",
		RunE: func(cmd *cobra.Command, args []string) error {
			return runClientList(cmd, args, values)
		},
	}

	registerClientSelectionFlags(command, values)

	return command
}

// runClientList lists clients across one or more instances.
//
// Parameters:
//   - cmd: Cobra command context.
//   - args: Unused positional arguments.
//   - values: Bound flag values selecting the target instances.
//
// Returns:
//   - error: An error when a selection, per-instance request, or output operation
//     fails.
func runClientList(cmd *cobra.Command, _ []string, values *selectionValues) error {
	selection, err := values.selection()
	if err != nil {
		return fmt.Errorf("select client instances: %w", err)
	}

	results, operationErr := app.NewClientManagement().List(cmd.Context(), selection)
	outputErr := writeClientList(cmd, results)

	err = errors.Join(operationErr, outputErr)
	if err != nil {
		return fmt.Errorf("list clients: %w", err)
	}

	return nil
}

// writeClientList renders successful list results in command output.
//
// Parameters:
//   - cmd: Cobra command receiving the rendered tables.
//   - results: Per-instance list results to render.
//
// Returns:
//   - error: Joined errors from every failed instance table.
func writeClientList(cmd *cobra.Command, results []app.ClientListResult) error {
	errs := make([]error, 0, len(results))
	for _, result := range results {
		err := writeClientListResult(cmd, result)
		if err != nil {
			errs = append(errs, err)
		}
	}

	return errors.Join(errs...)
}

// writeClientListResult renders one instance table.
//
// Parameters:
//   - cmd: Cobra command receiving the rendered table.
//   - result: One per-instance list result.
//
// Returns:
//   - error: An error when the instance table cannot be written.
func writeClientListResult(
	cmd *cobra.Command,
	result app.ClientListResult,
) error {
	if result.Index > 0 {
		cmd.Println()
	}

	if result.InstanceCount > 1 {
		cmd.Printf("Instance: %s\n", result.Instance)
	}

	tableWriter := output.NewTableWriter("INSTANCE", "NAME", "TYPE")
	for _, row := range result.Rows {
		tableWriter.Row(result.Instance, row.Name, output.FormatClientType(row.Automatic))
	}

	_, err := tableWriter.WriteTo(cmd.OutOrStdout())
	if err != nil {
		return fmt.Errorf("write instance %q: %w", result.Instance, err)
	}

	return nil
}
